# Stateful API keys

Optional `@arkenivajs/security-apikey` implements issuance, verification, atomic
rotation, revocation and bounded owner listing. It uses native random secrets
and an injected version-aware HMAC-SHA256 provider. It installs no route,
listener, pool or global credential cache. API keys convey no MFA assurance.

```typescript
import { createApplication } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import { apiKeyPlugin, APIKEY_CAPABILITY } from '@arkenivajs/security-apikey';
import type { ApiKeyPluginSettings, ApiKeyService } from '@arkenivajs/security-apikey';

export async function startCredentials(settings: ApiKeyPluginSettings) {
  const app = await createApplication({
    service: { name: 'partner-api', version: '1.0.0', environment: 'production' },
    plugins: [loggingPlugin(), apiKeyPlugin(settings)],
  });
  await app.start();
  return { app, keys: app.resolve<ApiKeyService>(APIKEY_CAPABILITY) };
}
```

Logging must be explicitly installed; the package declares its lifecycle
dependency without importing a concrete logger or SDK. Production requires
independently verified storage, secret and authentication providers. A label
cannot prove an implementation secure. Declared `test-only` providers are
rejected in production and development.

## Configuration and trust

| Required setting             | Meaning and bound                                                                                 |
| ---------------------------- | ------------------------------------------------------------------------------------------------- |
| `store.store`                | Complete durable `SecurityTransactionalStore`, including atomic batches, owner indexes and epochs |
| `store.securityLevel`        | `production` or `test-only`; no in-memory fallback                                                |
| `store.operationTimeoutMs`   | Integer 1–120000 ms, total operation deadline                                                     |
| `hmac`, `hmacKeyRef`         | Trusted HMAC-SHA256 provider and approved external reference, never a raw key                     |
| `authority`                  | Independent runtime account/session/tenant/policy authority                                       |
| `maxActiveKeysPerSubject`    | Integer 1–1000, scoped by issuer, subject and tenant                                              |
| `maxVerifyAttemptsPerMinute` | Integer 1–100000, shared verification budget                                                      |

`TrustedSecurityAuthority.require` receives a fixed `apikey.issue`,
`apikey.rotate`, `apikey.revoke`, `apikey.list` or `apikey.verify` action. Its
context additionally carries typed `apiKeyId` and `apiKeyPolicy` when applicable.
Success must approve the entire policy, including scopes, expiry and networks,
and return the same account/tenant binding after checking server-owned state.
Missing, inconsistent or unavailable authority fails closed.

Provider methods are captured once with their original receiver. Custom function
`bind`, `name` and `length` properties are never evaluated. Proxy providers and
callables, accessors and prototype traversal beyond 32 levels fail configuration
validation; replacing provider methods after construction has no effect.

Management authentication comes from trusted request/session context, including
recent step-up and management rate limits where required. A subject object is
only a target hint: cloning it or fabricating a tenant brand authenticates
nobody. `apikey.verify` runs only after HMAC proof and checks current account
policy without demanding an existing browser session. Never approve a scope
grant merely because an authenticated administrator requested it.

## Public operations

| Method                                  | Result and boundary                                                            |
| --------------------------------------- | ------------------------------------------------------------------------------ |
| `issue(subject, policy, options?)`      | One `ApiKeyIssue`; approved policy, quota guard and new record commit together |
| `verify(rawKey, {clientIp?}, options?)` | Fresh authorized `ApiKeyIdentity`; no cached acceptance                        |
| `rotate(id, authorization, options?)`   | New one-time secret; old deletion, new insertion and guard commit together     |
| `revoke(id, authorization, options?)`   | Deletes the owned version; absent records are an authorized no-op              |
| `list(subject, options?)`               | Frozen owner metadata without digest or secret                                 |

Case-sensitive tokens use `ak1.<UUID>.<secret>`, containing 32 cryptographically
random secret bytes. The prefix is only a lookup hint. Deliver the raw token
once to the correct authenticated recipient over TLS; never log it, put it in
a URL or browser storage, or assume JavaScript strings can be securely erased.

Records contain keyed verifiers, policy, timestamps and minimal binding hints.
Arbitrary identity claims and raw bearer credentials are not persisted.
Verification checks HMAC, expiry and source-network policy, obtains fresh
authority output, then re-reads the durable version. Revocation is observed at
that final read; stopping already authorized work requires application policy.

Policies allow 64 distinct ASCII scopes and 32 distinct CIDRs. Expiry is a valid
UTC timestamp with optional milliseconds. Native IPv4/IPv6 subnet checks reject
missing addresses under restricted policies, zone identifiers and IPv4-mapped
or embedded IPv6 inputs. Supply a socket address or a value established by
explicitly trusted proxy policy, never an unchecked header.

## Durable state and key rotation

The store must return an opaque backend `version` with generic reads and each
indexed record. Persist `ownerKey` and `expiresAt` as searchable metadata. The
[PostgreSQL reference](../../examples/postgres/security-state.md) verifies these
conventions. Partial backends, truncated lists and pre-commit acknowledgements
are unsupported. An owner guard serializes quota-changing transitions. Losing
credential predicates are denied without automatic transition retries; rotation
has no overlap period. Applications own retention, cleanup, backup and account
deletion.

The HMAC provider receives these explicit domains:

| Domain                            | Bound data and required policy                                                                         |
| --------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `arkenivajs.apikey.verifier.v1`   | Issuer, subject, tenant-or-empty, ID, secret; encode key version and retain required old verifier keys |
| `arkenivajs.apikey.owner.v1`      | Issuer, subject, tenant-or-empty; stable blind-index key while owner state exists                      |
| `arkenivajs.apikey.rate-owner.v1` | Fixed verification scope; stable blind-index key across participating pods                             |

Index output is formatted through SHA-256 to a fixed opaque key. Separately
manage stable blind-index material and rotating verifier keys: rotating an
index key would orphan quota/index state and needs a controlled migration.
Provider implementations must use adequate external entropy, version-aware
constant-time verification, bounded deadlines and approved reference/domain
allowlists. HMAC keys never enter the application database.

The attempt budget is shared across pods using the same store and stable
rate-owner domain/reference, including unknown IDs. It is a fixed server-clock
minute window, not a rolling or per-IP guarantee. Up to eight retries apply
only to definitively rejected counter CAS predicates, with abortable 1–3 ms
jitter between attempts, never to ambiguous writes.
Contention may deny admission. Budget exhaustion denies valid and invalid keys;
deploy independent trusted ingress policy appropriate to that tradeoff.
Every lookup reaching verification performs one provider HMAC check, including
a dummy negative lookup. This reduces cheap misses without promising constant
end-to-end timing across database and authority I/O.

Authenticated management methods additionally share a fixed 1000-attempt
per-owner, per-minute durable budget across pods. Requests denied by the
independent authority never reserve storage state. This bound complements the
application's more restrictive management and ingress policies.

## Bounds, errors and lifecycle

Each instance admits 32 operations without a queue. Timed-out providers retain
their slots until they settle. Callers can reduce the configured positive
deadline. Zero, forged signals, unknown options and request clock overrides
fail before provider work. Shutdown cancels work and closes handles; injected
providers remain application-owned.

Identity hints are limited to 16 KiB, 512 nodes and 12 levels. Lists allow at most
1000 records and 1 MiB of decoded record data. Accessors, cycles, malformed
Unicode, pollution fields and lossy JSON values are rejected. Backend query
and materialization bounds remain the backend's independent responsibility.

Errors contain fixed English messages without private causes. Validation uses
`EK_CONFIG_INVALID`; invalid credentials/authority use `EK_APIKEY_INVALID`;
expiry uses `EK_APIKEY_EXPIRED`; final-read invalidation uses
`EK_APIKEY_REVOKED`; provider/state failure uses `EK_APIKEY_STORE`.
`EK_ABORTED`, `EK_TIMEOUT`, `EK_RESOURCE_CLOSED` and `EK_BACKEND_UNAVAILABLE`
retain cancellation/deadline/close/admission meaning. Interrupted writes report
`outcome: 'unknown'`; reconcile durable state instead of assuming rollback.

Audit events contain fixed operation/outcome classifications. Optional telemetry
exports `apikey.<operation>` spans, `.duration` histograms in milliseconds and
`.completed.ok`/`.completed.error` counters, with no key/account/tenant labels.
The actual SDK regression checks exports, drops and privacy. No monetary costs
or cluster-wide resource attribution are calculated.

Run `pnpm --filter @arkenivajs/security-apikey test`, strict type checks and the
[executable PostgreSQL guide](../../examples/postgres/api-keys.md). Unit state
models alone are not durable conformance. Production release additionally
requires deployment/provider review, performance evidence and required CI gates.
