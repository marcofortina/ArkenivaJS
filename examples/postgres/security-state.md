# Durable transactional security state

This application-owned reference implements the complete `SecurityTransactionalStore`
SPI on an existing named `SqlProvider`: one-use claims, versioned read/CAS,
all-or-nothing batches, bounded owner indexes and monotonic revocation epochs.
It creates no additional pool and authenticates no user, session or API key by
itself. Credential services must independently verify authority, tenant,
secret digests, policy and expiry before returning authentication results.

Use the [private disposable TLS fixture](../../packages/database-postgres/test/fixtures/README.md)
and the workspace's pinned Node/pnpm versions. The environment loader keeps
database credentials outside command arguments and tracked files:

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm --filter @arkenivajs/example-postgres test
python3 packages/database-postgres/test/fixtures/run.py /private/postgres/environment.json pnpm --filter @arkenivajs/example-postgres test:integration
python3 packages/database-postgres/test/fixtures/run.py /private/postgres/environment.json pnpm test:packed:examples --integration postgres
```

The private mapping must supply `DATABASE_URL` and
`ARKENIVA_POSTGRES_DISPOSABLE=1`. Each integration test creates a fresh random
`security_` schema, initializes its tables, and drops only that owned schema in
`finally`. The reference advertises `securityLevel: 'test-only'` and refuses an
absent disposable marker or arbitrary schema name. Production migration,
retention, backup, account lifecycle and secret policy are application-owned;
this fixture is not a production storage deployment.

## Use the injected connection

```typescript
import { createPostgresSecurityStateStore } from './src/security-state-store.js';

const state = createPostgresSecurityStateStore(app.sql, 'main', ownedSchema);
const created = await state.compareAndSet('credentials', recordId, null, {
  ownerKey: approvedOwnerDigest,
  expiresAt: expirationUtc,
  enabled: true,
});
if (!created.committed) throw new Error('Credential state already exists');
const stored = await state.read('credentials', recordId);
// Use the backend-issued stored.version for the next CAS; never synthesize it.
```

The complete runnable fixture, independent-process workers and negative cases
are in [the integration suite](test/integration/security-state.integration.test.ts).
Public shapes used by the reference are in [the SPI module](src/security-store-contracts.ts).
The owner digest must come from an approved domain-separated HMAC provider over
verified issuer/subject/tenant ownership. A username, tenant string, TypeScript
object or successful database write is not proof of authentication. The test
suite's random opaque owner labels identify only synthetic rows.

## Atomic behavior

`claimOnce(namespace,digest,expiresAt)` uses one conditional PostgreSQL upsert.
Only one process wins while the claim remains live. The database clock controls
expiration; an already-expired requested claim cannot succeed. An expired
claim can be reclaimed with a new valid expiry. Credential code must validate
its own original TTL before claiming, rather than extending an expired token.

`compareAndSet` treats `expectedVersion: null` as create-if-absent and a
backend-issued revision as update/delete-if-current. Expired records are
logically absent. State IDs and versions are opaque; this reference emits fresh
UUID revisions. `next.ownerKey` is required for an ordinary create/update and
cannot change the live record's owner. A null next value deletes only when its
version predicate holds. An absent-to-absent operation is a successful no-op.

The returned read record contains its fields plus reserved `version` metadata.
Callers cannot persist a forged `next.version`. `ownerKey` and optional
`expiresAt` are denormalized into indexed columns and checked against the stored
body when read; corrupt metadata fails closed. `SecurityIndexedRecord.fields`
contains application fields, while its separate `version` is the same durable
revision. Returned nested values are frozen snapshots.

`atomicBatch` accepts 1–32 distinct record predicates. Every process acquires
locks in the same namespace/ID order. A conflict throws internally through the
SQL transaction so earlier mutations roll back; only after successful rollback
does the caller receive `committed: false`. A successful batch's changed rows
share one fresh receipt revision. Owner predicates apply to every mutation;
creation cannot silently reassign a live row belonging to another owner.

`listByOwner` always includes namespace and owner predicates and uses the
dedicated `(namespace,owner_key,id)` index. Its limit is 1–1000. It fetches one
extra row to detect overflow and rejects the whole result instead of returning
a truncated list. Expired rows are excluded. A selective live query with 2000
foreign rows verifies the actual owner index appears in the PostgreSQL plan.

`bumpOwnerEpoch` atomically increments a namespace/owner counter; an absent
owner starts at zero through `currentOwnerEpoch`. Independent processes observe
strict increases. JavaScript safe-integer overflow is rejected without changing
the counter. Credential services must bind issued sessions to their current
owner epoch and recheck it on validation; this store does not issue sessions or
promise that a caller has performed that check.

## Bounds, failures and ownership

Record bodies use bounded JSON text with a 32 KiB database constraint. This
preserves finite number spellings and prevents JSONB formatting or numeric
expansion from amplifying materialized rows. Inputs allow bounded plain JSON:
16 nesting levels, 1024 nodes, 64 properties per object, 256 array entries and
256 UTF-16 units per property name. Undefined, nonfinite/negative-zero numbers,
functions, bigint, native object prototypes, sparse arrays, accessors,
prototype-pollution keys, NUL and malformed Unicode are rejected. The body limit
includes injected ownership metadata; application state must store protected
secrets or keyed digests rather than plaintext credentials.

A batch has at most 1 MiB of serialized bodies; a decoded owner list has at most
1 MiB. The SQL result has at most 1001 rows, each constrained to 32 KiB. These
row/materialization limits do not bound server-side query work. Table retention
and quota maintenance are not implemented by this disposable reference.

Each store instance admits at most 16 operations without a hidden queue. Its
default and maximum deadline is 5000 ms; callers can reduce it to any positive
integer. Cancellation propagates to the injected driver. An uncooperative
backend retains its admission slot until it actually settles, and late results
cannot acknowledge an operation after its deadline. Per-instance limits are
not a cluster-wide budget.

Validation failures use `EK_CONFIG_INVALID`; saturation uses
`EK_BACKEND_UNAVAILABLE`. Backend failures use a fixed
`EK_DATABASE_UNAVAILABLE` message without native causes or stored values.
Interrupted calls retain `EK_ABORTED`/`EK_TIMEOUT`. A failed write reports
`details.outcome: 'unknown'` conservatively: timeout or connection loss is never
reported as proof that a write rolled back. Do not blindly retry one-use or
non-idempotent work; reconcile durable state through the application's trusted
operation policy. Only a normally acknowledged SQL commit returns a successful
mutation receipt.

The injected application owns SQL resources and shuts them down. The adapter
owns no listener, socket, global map or connection pool. Tests verify actual
PostgreSQL behavior, schema cleanup, namespace/owner isolation, batch rollback,
shared claims/CAS/epochs across independent Node processes, metadata corruption,
TTL, bounds and backend outage. Type compatibility and unit tests alone are not
a live storage conformance claim.
