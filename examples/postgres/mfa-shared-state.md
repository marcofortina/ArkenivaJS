# Durable MFA state reference adapters

This application-owned example implements `MfaStateStore` against real
PostgreSQL, with a shared `MfaRateLimitStore`. It demonstrates shared atomic state before the optional factor
services are available. It does not verify a factor, issue a session or implement
the TOTP-factor or WebAuthn-credential stores. It also demonstrates the durable
evidence handoff described below using synthetic test records.

## Setup and execution

Use the supported Node/pnpm workspace and the disposable PostgreSQL TLS fixture
described in the [orders guide](README.md). Inject its least-privilege
`DATABASE_URL` through the documented protected environment. The database role
must be allowed to create/drop its own isolated schemas. No production data or
credentials are suitable for this example.

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm --filter @arkenivajs/example-postgres test
export ARKENIVA_POSTGRES_DISPOSABLE=1
pnpm --filter @arkenivajs/example-postgres test:integration
```

Unit checks need no service. The integration command requires `DATABASE_URL`
and the explicit disposable marker; it never silently skips a missing server.
Each test creates a random `mfa_<24 hexadecimal digits>` schema, creates its
challenge table, then drops only that owned schema and closes application pools.

## Application adapter and ownership

The complete source is [src/mfa-state-store.ts](src/mfa-state-store.ts).
`createPostgresMfaStateTable(sql, connection, schema)` creates the table in an
already-owned disposable schema. `createPostgresMfaStateStore(sql, connection,
schema)` returns the shared public `MfaStateStore` interface. Both refuse an
absent disposable marker or an unsafe schema. They import framework entry points
and preserve the SQL adapter's deadline/cancellation contract.

A challenge contains an opaque ID, ceremony purpose, issuer, optional
subject/tenant/session/RP, SHA-256 hexadecimal challenge digest and UTC ISO
creation/expiry timestamps. IDs use 1–128 ASCII letters, digits, dots, underscores,
colons or hyphens; text fields are nonempty, at most 1024 characters and contain
no controls. Raw proof, OTP, provisioning URI and unexpected fields are rejected.
These are explicit reference-adapter input bounds, not a new authentication
mechanism. Obtain ownership and `now` from a trusted server authority/clock;
never copy them from HTTP parameters or tenant headers.

Creation inserts once. A duplicate ID rejects without replacing the original
record. Claiming uses one `DELETE ... RETURNING` with exact issuer, purpose,
subject, tenant, primary session and RP predicates plus an expiry check. NULL-safe
equality means an omitted owner field cannot match an owned ceremony. One SQL
statement provides atomic consumption across independent application processes.
A wrong owner, expired/missing challenge or reuse returns `null`. Explicit
discard removes one opaque ID.

SQL failures become safe `EK_MFA_STORAGE`; abort/deadline errors retain their
common codes. A lost response may mean the challenge was consumed: reject the
verification and begin a new ceremony rather than retrying for success. Stored
data is validated after consumption; corrupt metadata cannot grant evidence.
The generic PostgreSQL adapter preserves JSONB as text; this reference parses a
bounded string-only record and rechecks that its owner/purpose/expiry agree with
the atomic SQL match. Corrupt JSON metadata cannot substitute a foreign owner.
This disposable example removes its complete schema after execution. A
production adapter needs controlled migrations, grants and bounded expiry
cleanup in addition to the required shared state/limiter/evidence contracts.

## Verified behavior and diagnosis

Integration checks reject a changed issuer, subject, tenant, session, RP,
purpose and expired timestamp without consuming the valid owner's challenge.
An already-aborted claim cannot consume the valid record. The valid claim
succeeds once; reuse and discard return no record. A barrier
starts claims from two separate Node processes using independent SQL pools:
exactly one succeeds, and the parent cannot consume again.

Missing service/credential configuration must fail explicitly. A TLS/network or
storage failure requires restoring the verified fixture; never disable TLS
verification. Tests and logs print no DSN, factor secret or credential material.
Future factor modules still require their own verifier, replay/counter/recovery,
secret protection, distributed rate-limit, evidence-handoff and end-to-end tests.

## Shared atomic attempt limiter

[src/mfa-rate-limit-store.ts](src/mfa-rate-limit-store.ts) implements the shared
`MfaRateLimitStore` port. Create its table with
`createPostgresMfaRateLimitTable(sql, connection, schema)` and obtain the adapter
with `createPostgresMfaRateLimitStore(sql, connection, schema)`. It uses the same
explicitly disposable fixture, cleanup and cancellation/error policies above.

`checkAndRecord({scopeKey,operation,maxAttempts,windowMs,nowMs}, options?)` performs
one `INSERT ... ON CONFLICT ... RETURNING` transition. Its primary key is a
SHA-256 digest of a versioned JSON-framed scope/operation tuple, avoiding index
size failures for long Unicode keys and storage of raw account scope strings.
This digest is a lookup key, never authentication evidence. Derive the original
strings and the time from trusted server policy;
request parameters cannot choose another account's scope or a weaker limit.
The text bounds above apply. Capacity/window/time must be safe JavaScript
integers, capacity/window positive and time nonnegative. Capacity plus one and
time plus window must remain safe integers. PostgreSQL BIGINT storage and
explicit bigint comparisons preserve the values without narrowing to 32 bits.

A granted attempt returns `{allowed:true}`. Exhaustion returns
`{allowed:false,retryAfterMs}`. The counter saturates at capacity plus one;
it is a bounded limiter state, not an exact audit count of every rejected call.
The window resets only at its original end. Different capacity/window settings
for the same active bucket fail with `EK_MFA_POLICY` rather than reopening quota;
changed policy may take effect after the existing window expires. A backward
clock jump conservatively exhausts the existing bucket until its original end.
Storage failures never grant an attempt.

The same integration command tests independent scope/operation buckets, exact
boundary/reset/retry values, conflicting active policies, clock rollback and two
separate Node processes contending for one capacity-three bucket. Ten attempts
collectively receive exactly three grants. Unknown/noninteger/overflowing
inputs are rejected before SQL, and backend errors remain safe and fail closed.

## Server-side single-use evidence handoff

[src/mfa-evidence-store.ts](src/mfa-evidence-store.ts) implements
`MfaEvidenceStore`. Create its table with
`createPostgresMfaEvidenceTable(sql, connection, schema)` and obtain its port with
`createPostgresMfaEvidenceStore(sql, connection, schema)`. This remains an
application-owned disposable reference with no factor verifier or session issuer.
The tests deliberately construct synthetic records to verify persistence; they
do not establish that a user completed a real factor.

`recordOnce(record, options?)` may be called only by trusted successful factor
verification code. Records bind an opaque evidence ID, method, assurance,
issuer, subject, optional tenant, primary session and verification/expiry times.
Raw OTP/assertion/provisioning data and undeclared fields are rejected. TOTP
and recovery-code records cannot claim phishing-resistant assurance.

The application's independent session authority calls
`consume({evidenceId,issuer,subject,tenantId?,primarySessionId,now}, options?)`
with its current authenticated owner and server clock. One SQL update matches
all owner fields, an unused record and the exact validity window. A wrong
owner/session, expired/future proof or reuse returns `null` without granting
assurance. Missing optional tenant cannot match a tenant-bound record. An
already-aborted request cannot consume the proof.

Successful consumption retains a `consumed_at` tombstone. A later insertion
with the same ID still fails, including after successful consumption, so a
retry cannot reconstruct a used proof. Retain those rows through expiry under
the production cleanup policy. The disposable example drops the entire owned
schema after its tests.

Method, assurance and validity are stored separately from the JSON body and
checked again before returning evidence, together with the exact owner/session.
Corrupt JSON cannot substitute another owner, change verified factor class,
increase assurance or alter proof freshness. Storage uncertainty rejects the
handoff. A session authority that crashes after consuming but before recording
its session upgrade must start a new verification rather than re-create proof.

The integration command covers duplicate insertion before and after use,
issuer/tenant/account/session mismatches, expiry/future timestamps, cancellation,
corrupt metadata and two independent authority processes contending for the
same evidence. Exactly one receives it. No browser bearer credential, cookie,
JWT, automatic identity upgrade or monetary record is produced by this adapter.

## Process death and unavailable providers

The failure suite terminates only its own dedicated Node child with `SIGKILL`
after an acknowledged record/consume operation. The parent checks the actual
termination signal and reads state through an independent connection. A record
survives producer death; a consumed proof stays consumed after authority death
and cannot be re-recorded.

A separate application first exercises all three real SQL-backed stores, then
closes its own pools. Retained store handles must reject with `EK_MFA_STORAGE`,
without consuming a challenge/evidence or granting an attempt. A healthy
application sharing the tables verifies that the failed operations changed no
state. This tests unavailable/closed providers without stopping the shared test
database. It is not a database-server failover or network-partition claim.
