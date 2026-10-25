# Durable MFA state reference adapters

This application-owned example implements `MfaStateStore` against real
PostgreSQL, with a shared `MfaRateLimitStore`. It demonstrates shared atomic state for optional factor
services. It does not verify a factor, issue a session or implement
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
Factor modules require their own verifier, replay/counter/recovery,
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

## Verified primary identity and application authority

The executable
[authority test](test/integration/mfa-authority.integration.test.ts) connects the
durable evidence adapter to actual OIDC verification. A disposable loopback
issuer signs test tokens using a fresh private key retained in its closure.
`createAuthService` validates signature, issuer, audience and lifetime. The
application derives tenant ownership with `auth.tenantFrom(identity)`, requires
a signed primary session ID and primary authentication within five minutes,
and builds `MfaSubjectContext` from those verified values. Cloning an identity
does not preserve runtime provenance. No request user ID or tenant header is
used as an authenticated account.

Only the application's authority consumes the stored evidence for that exact
issuer/account/tenant/session. Wrong ownership, stale/future primary
authentication and replay cannot produce a step-up. The original identity
stays single-factor. After successful consumption, the **test application
issuer**, not a framework factor or store, signs a new token bound to the
same owner and original primary authentication time. No token is logged or
returned by an HTTP endpoint.

The verifier explicitly maps that fixture issuer's exact `acr` value
`urn:example:local-mfa` and a factor verification timestamp within one minute.
Missing, unknown, stale or future claims fail closed. Claims merely named
`mfa`/`amr` are ignored. The new token must be verified again before
`auth.requireAssurance(identity, 'mfa')` succeeds. TOTP-class evidence cannot
authorize phishing-resistant assurance; cloned identities remain rejected.

The application also demonstrates a strict management policy: every enroll,
replace, disable, recovery-code or revoke decision needs the current verified
owner, `mfa:manage` scope, recent primary authentication and recent MFA. This
illustrates an already-enrolled account's management authorization. Initial
enrollment bootstrap/account recovery needs a separately approved application
reauthentication policy; this fixture supplies neither that workflow nor real
factor verification. The synthetic producer only exercises the shared trust
handoff. Factor modules, a real IdP integration and production session lifecycle
still require their own tests and deployment policy.

## Authenticated encryption and key rotation reference

[src/mfa-secret-protector.ts](src/mfa-secret-protector.ts) implements the shared
`MfaSecretProtector` SPI with Node's AES-256-GCM. This application-owned fixture
requires the same explicit disposable marker. It is not a production key manager
or a factor service. Its factory takes an active version ID and a trusted async
resolver returning exactly 32 key bytes from an application-selected provider.
No key is created implicitly, logged or returned through the SPI.

`seal` copies 1–4096 plaintext bytes before asynchronous key retrieval, uses a
fresh random 12-byte nonce, and returns a version ID plus canonical Base64
ciphertext, nonce and 16-byte authentication tag. Associated data is a framed,
versioned tuple containing key ID, issuer, subject and optional tenant. Absence
of a tenant is distinct from a tenant-bound envelope. Every owner field and
the key version must match when opening; authenticating the final GCM tag must
succeed before any plaintext is returned.

A new protector instance selects a new active key version. Existing envelopes
remain readable while the resolver retains their old key. Removing a key or
returning an invalid key fails closed; the adapter never silently resets a
factor. This demonstrates version selection/decryption, not database rekey
migrations or production KMS authorization. A production deployment must own
key access, per-key usage limits, rotation, backup and migration policy while
preserving factor replay state. Random nonces in this bounded fixture do not
replace those deployment controls.

Inputs are bounded and copied without invoking accessors. Cancellation and
monotonic deadlines apply to key retrieval; late key results cannot resume
crypto work after rejection. Owned key/plaintext/intermediate decryption
buffers are cleared, while provider-owned retained keys remain unchanged.
The caller owns returned plaintext and must clear it when finished; JavaScript
does not provide a complete process-memory erasure guarantee.

The service-independent unit suite checks fresh envelopes, every owner binding,
ciphertext/nonce/tag/version tampering, missing keys, rotation, mutable input
snapshots, unavailable providers, cancellation, deadlines, late key completion,
input bounds and safe error serialization. It uses ephemeral synthetic bytes,
prints no keys or factor material, and leaves PostgreSQL state untouched.

## Durable TOTP factor state

[src/totp-state-store.ts](src/totp-state-store.ts) implements the complete
`TotpStateStore` SPI using three additional owned PostgreSQL tables. It is
explicitly classified `usage:'test-only'` and requires the disposable marker;
production TOTP configuration rejects this fixture. It supplies real shared
SQL atomicity for tests, not a production migration or deployment package.

Pending enrollment inserts once with its exact owner, primary session,
expiration and observed factor generation. Consumed IDs remain tombstones.
An account row lock serializes activation, replacement, revocation and recovery
set changes. Activation validates the pending generation and ownership, installs
the encrypted factor and accepted timestep, consumes all pending enrollments
and removes the old recovery set in one transaction. A replacement keeps the
old active factor until that transaction commits. The factor service must
authorize enrollment/replacement independently before these store operations.

`acceptStepIfGreater` is one conditional update bound to issuer, account,
tenant, active factor ID and generation. It advances the exact stored step
only if greater. Body metadata and independent SQL columns are compared on
reads; corrupt ownership/generation/step data cannot be returned as a valid
factor. Key migration must preserve ID, generation and accepted step.

Recovery replacement deletes and inserts the complete keyed-hash set in one
transaction. Consumption uses the same owner lock and an atomic deletion;
revocation invalidates the factor, pending enrollments and recovery set together.
Owner and hash lookup indexes use SHA-256 over framed/bounded values, retaining
exact owner/hash predicates. These lookup digests are not authentication or a
substitute for the service's external-key HMAC. No recovery plaintext, TOTP
seed or encryption/HMAC key belongs in these tables.

The fixture bounds replacement sets to 100 distinct keyed hashes. An empty set
explicitly clears recovery state; the service must issue at least ten random
codes. It accepts a trusted construction-time test clock for deterministic
pending expiration. No request can choose the clock.

The integration suite uses real signed primary identities and verifies owner,
tenant and session mismatch, expiry, stale generations, replacement/revocation,
metadata corruption and rollback after a real SQL trigger failure following
recovery deletion. Two separate Node processes contend for enrollment activation,
the same OTP step and the same recovery hash; each transition has exactly one
winner. These are storage transitions; actual OTP verification and service
authorization require the additional factor-service tests.

## Public TOTP service integration

[The factor-service tests](test/integration/totp-service.integration.test.ts)
import `createTotpService` from the public package entry point. Their
[application authority](test/integration/totp-service-fixture.ts) verifies actual
OIDC provenance with the existing auth service, exact tenant/session ownership,
scopes and a fixture-issuer-specific signed recent reauthentication policy.
Only authority-owned contexts are registered. A copied subject or management
grant cannot acquire provenance by preserving its fields.

The fixture explicitly approves initial enrollment/replacement after that
independent reauthentication. For recovery/disable management it first consumes
real stored factor evidence for the exact owner/session, then creates its own
short-lived authority grant. The framework cannot mint such grants or upgrade
an existing verified identity. These are controlled test-authority decisions,
not a production account-recovery policy or a live external IdP accreditation.

The same integration command above executes enrollment, real otplib proof,
PNG provisioning, confirmation, verification, external-key recovery rotation,
regeneration and disabling. It checks prescribed drift/TTL, shared rate limits,
foreign tenants/sessions, fabricated objects, corrupt secret bytes, failed
providers and lost acknowledgments. Pending ciphertext and recovery hash rows
are inspected without printing provisioning or recovery material.

A dedicated barrier starts two full factor-service Node processes with separate
SQL pools. The parent authenticates the fixture context before handing it across
its closed authority channel. Ephemeral synthetic keys and proofs are delivered
only through owned stdin pipes, never command arguments or stdout. The child
authority remains test-only and cannot be configured in production. Exactly one
process accepts each shared OTP/recovery proof. No production credential enters
these tests; fixture keys are cleared and only the owned schema is removed.

The application-owned [recovery MAC reference](src/mfa-recovery-hmac.ts) implements
`TotpRecoveryHmacProvider` with standard Node HMAC-SHA256. Its secret resolver is
separate from PostgreSQL account data; only version/key-ID-qualified verifier
strings enter SQL. The reference is explicitly `securityLevel:'test-only'` and
requires disposable opt-in. Production deployments must provide a reviewed
external secret/KMS backend; raw key export is not required by the public SPI.
The encoding binds version, domain, issuer, tenant absence/value, subject, active
factor ID and code. The approved rotation snapshot contains at most eight distinct
versions and must include the current one. No code, key, verifier or provider
diagnostic is printed.

The factory defaults to production validation; deterministic `clock.nowEpochMs()`
is allowed only in the test environment. Recovery generation defaults to ten
codes and accepts integer counts up to twenty. Integration checks include twenty
independent codes, a replayed management grant, changed active-factor binding,
key retirement, and duplicate/oversized/failing MAC candidate providers before
any durable consumption. Management grants are consumed by the independent
fixture authority once; applications must enforce their own durable authority
policy across processes.
