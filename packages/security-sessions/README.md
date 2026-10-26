# Stateful server sessions

Optional `@arkenivajs/security-sessions` provides creation, validation, atomic
renewal, individual revocation and global owner revocation. It uses native
random secrets, external version-aware HMAC-SHA256 and a complete shared
transactional store. It installs no HTTP routes, listeners or database pools.

```typescript
import { createApplication } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import { sessionsPlugin, SESSIONS_CAPABILITY } from '@arkenivajs/security-sessions';
import type { SessionsPluginSettings, SessionService } from '@arkenivajs/security-sessions';

export async function startSessions(settings: SessionsPluginSettings) {
  const app = await createApplication({
    service: { name: 'browser-api', version: '1.0.0', environment: 'production' },
    plugins: [loggingPlugin(), sessionsPlugin(settings)],
  });
  await app.start();
  return { app, sessions: app.resolve<SessionService>(SESSIONS_CAPABILITY) };
}
```

## Configuration and trusted identity

Settings require `store`, `hmac`, `hmacKeyRef`, `authority`, `defaultPolicy` and
`maxSessionsPerSubject`. The store implements all seven
`SecurityTransactionalStore` methods, including backend versions, atomic
batches, bounded owner indexes and monotonic owner epochs. The existing
[PostgreSQL reference](../../examples/postgres/security-state.md) demonstrates
this port. There is no in-memory production fallback.

`store.operationTimeoutMs` is an integer from 1 to 120000. The owner limit is
an integer from 1 to 1000, scoped by issuer, subject and tenant. Policies require
positive integer absolute and idle TTLs; absolute TTL is at most 31 days and
idle TTL is at most seven days and cannot exceed absolute TTL.
`maxConcurrentSessions` can reduce the configured owner limit. SameSite defaults
to `lax`; an explicit authority must approve the complete requested policy.

`SessionIdentityAuthority` extends `TrustedSecurityAuthority` with the required
`resolveIdentity(identity, context, options?)` method. This typed completion
provides the runtime identity and original authentication metadata required for
secure session handling. A `require` callback alone cannot reconstruct those
facts safely. The five service methods retain their prescribed signatures.

For creation, the resolver authenticates an independent primary session using
server-owned state and returns the canonical account, verified tenant,
`authenticatedAt` and optional `assuredAt`. Caller-provided claims, roles,
assurance and TypeScript tenant brands are never proof of authentication.
Validation and renewal call the resolver after token proof to check current
account and tenant policy. They preserve the original authentication time,
assurance and MFA time; ordinary activity never counts as fresh MFA.

`require` approves every fixed `sessions.create`, `sessions.validate`,
`sessions.renew`, `sessions.revoke` or `sessions.revoke_all` action. Its typed
context includes the applicable session ID, complete policy and trusted
assurance. Management must independently authenticate the caller and enforce
recent step-up where needed. Bearer validation does not require a separate
browser session. Missing, inconsistent, denied or unavailable providers fail
closed. Production and development reject explicitly marked test-only
providers; a production label does not replace provider review.

## Operations and durable state

| Method                               | Effect                                                                                                        |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------------- |
| `create(identity, policy, options?)` | Returns a new opaque token only after quota guard and session commit                                          |
| `validate(token, options?)`          | Returns fresh canonical identity and slides idle expiry within the original absolute deadline                 |
| `renew(token, options?)`             | Atomically deletes the old credential and creates a replacement; preserves authentication and absolute expiry |
| `revoke(sessionId, options?)`        | Authorizes management before lookup and deletes the owned version                                             |
| `revokeAll(subject, options?)`       | Atomically advances the shared owner epoch and returns that newly committed epoch                             |

`revokeAll` returns an exact monotonic epoch, not an estimated active-session
count. Every older epoch is denied across participating pods. New issuance
cleans obsolete rows under the quota guard before applying the owner limit.
Concurrent renewal has one winner; ambiguous transitions are never retried as
though they rolled back. An already authorized application operation needs its
own cancellation policy if it must stop immediately after logout.

Tokens use `ss1.<UUID>.<secret>` with 32 cryptographically random secret bytes.
Persisted records contain a versioned keyed verifier, minimal owner hints,
original authentication metadata, policy and expiry. Raw credentials and
arbitrary upstream claims are not stored. The verifier binds the owner, token,
epoch, policy, assurance and timestamps. No cached acceptance bypasses storage.

External HMAC domains are `arkenivajs.sessions.verifier.v1`,
`arkenivajs.sessions.owner.v1` and `arkenivajs.sessions.rate-owner.v1`.
The verifier provider retains required old key versions during rotation.
Owner/rate domains require independent stable blind-index material while
shared records exist. Index results are formatted through SHA-256. Keys never
enter the database; use approved reference/domain allowlists, adequate external
entropy and constant-time version-aware verification.

All verification attempts share a durable fixed-minute budget of 10000, and
authenticated management shares 1000 attempts per owner per minute. Only
definitively rejected counter predicates receive up to eight bounded
re-evaluations with abortable jitter. Credential transitions have no automatic
retry after an ambiguous write. Deploy independent trusted ingress controls
appropriate to the risk of exhausting a shared budget.

## HTTP boundary and logout

The application sends `SessionIssue.value` using its `__Host-session` cookie
name with `Secure; HttpOnly; Path=/` and the authorized SameSite policy.
Never set Domain, transmit the value in URLs or expose it through JavaScript
storage. Cookie-authenticated state-changing routes must enforce a trusted
Origin/Referer policy and CSRF protection. TLS termination and trusted proxy
configuration remain explicit application responsibilities.

The session module does not authenticate arbitrary logout request objects.
An application must verify the configured issuer, signature, audience, expiry,
logout-event shape and bound `sid`/`sub`/tenant, and reject replay atomically
before invoking its authorized revocation policy. The PostgreSQL integration
fixture exercises signed logout events and shared state; it is a controlled
test authority rather than a production identity provider.

## Bounds, errors and observation

Each instance admits 32 operations without a queue. A timed-out or cancelled
provider retains its permit until it settles. Callers may reduce a positive
configured deadline; zero, malformed signals, unknown options and request clock
overrides are rejected. Shutdown cancels calls and invalidates handles, while
injected providers remain application-owned. Interrupted writes report
`outcome: 'unknown'`; reconcile actual durable state instead of assuming rollback.

Input snapshots reject accessors, cycles, pollution fields, malformed Unicode
and lossy JSON. Identity snapshots are bounded to 16 KiB, 512 nodes and 12
levels; owner lists are bounded to 1000 records and 1 MiB without silent
truncation. Backend query/materialization limits remain the backend's duty.

Errors use fixed English messages without provider causes. Credential,
expiry, revocation and storage failures use `EK_SESSION_INVALID`,
`EK_SESSION_EXPIRED`, `EK_SESSION_REVOKED` and `EK_SESSION_STORE`; configuration,
cancellation, deadline, closed resources and admission retain their core codes.
Optional scoped telemetry and audit contain fixed operation/outcome names,
never cookie, identity, tenant or keyed-verifier labels. No resource cost is
calculated.

Run `pnpm --filter @arkenivajs/security-sessions test` and the real PostgreSQL
integration tests. Durable conformance requires independent application
instances and transactional backend tests. Deployment review, required CI and
performance evidence remain separate release requirements.
