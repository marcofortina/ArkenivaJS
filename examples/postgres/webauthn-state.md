# Durable WebAuthn credential reference

[src/webauthn-state-store.ts](src/webauthn-state-store.ts) implements the public
`WebAuthnStateStore` using the application's existing named `SqlProvider` and pool.
It is a disposable reference, marked `usage: 'test-only'`; the production-default
factor service rejects it. A production application must provide reviewed migrations,
grants, retention and operational policy through the same public interface.

Use the [disposable TLS setup](README.md) with `DATABASE_URL` and
`ARKENIVA_POSTGRES_DISPOSABLE=1`. No host container engine is necessary when the
database fixture runs in a dedicated VM. The tests create a random owned schema,
drop it on completion and stop every application pool and child process.

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm --filter @arkenivajs/example-postgres test
pnpm --filter @arkenivajs/example-postgres test:integration
```

Create the shared challenge table with `createPostgresMfaStateTable`, then the
account and credential tables with `createPostgresWebAuthnTables`. Obtain the
adapter with `createPostgresWebAuthnStateStore(sql, connectionName, schema)`.
The optional fourth clock argument is a trusted test fixture dependency, never
an HTTP request value. The factor authority must independently authenticate and
authorize every bound operation before the adapter is called.

Account identity includes RP, issuer, subject and tenant presence/value. An atomic
find-or-insert allocates 32 random bytes once. Database uniqueness covers both
account identity (including absent tenant) and RP/user handle. Credentials use a
global RP/credential primary key and a foreign key to that account's exact handle.
Revocation retains the account mapping and credential tombstone.

PostgreSQL generates initial and subsequent opaque UUID revisions through its
[native UUID function](https://www.postgresql.org/docs/17/functions-uuid.html).
The caller's candidate marker is never persisted as the credential revision.
Every successful assertion write changes the revision, including counter `0 → 0`.
Row locks and explicit full-binding/version/counter predicates serialize mutations
across independent processes. A stale assertion returns `conflict`; the adapter
never retries it. A nonzero counter must strictly increase. Backup eligibility is
immutable; backup state may change. Revocation uses the same row lock/revision and
atomically removes the account's pending registration and bound authentication
ceremonies. Passwordless attempts still fail against the revoked credential.

Public-key bytes are bounded at 16 KiB and copied without invoking custom iterators.
The JSONB immutable metadata envelope is bounded at 32 KiB. Every read independently
compares its owner/RP/handle/credential metadata to the relational columns. Active
credential reads reject more than 100 rows without returning a partial collection;
revoked tombstones do not fill the active credential budget. Corrupt data, failed
or uncertain writes, cancellation and deadline expiry cannot become success.

The integration suite uses real PostgreSQL and separate Node processes for handle
allocation, duplicate insertion, zero/increasing counter races and revocation races.
Storage fixtures use synthetic public-key bytes and do not claim cryptographic or
browser interoperability. The factor package's signature tests and controlled
browser/service acceptance remain separate checks. Never log account handles,
credential IDs, signatures, browser responses, database credentials or evidence.
