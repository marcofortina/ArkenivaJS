<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 Marco Fortina <marco_fortina@hotmail.it> -->

# Single-use magic links

Optional `@arkenivajs/security-magiclink` provides `magicLinksPlugin(settings)`
and `MAGICLINK_CAPABILITY`. Native `node:crypto` generates 32-byte random bearer
secrets. External version-aware HMAC-SHA256 and an application-owned shared
transactional store protect persisted state. No mail transport, route, database
pool or session is installed implicitly.

```typescript
import { createApplication } from '@arkenivajs/core';
import { loggingPlugin } from '@arkenivajs/logging';
import { magicLinksPlugin, MAGICLINK_CAPABILITY } from '@arkenivajs/security-magiclink';
import type { MagicLinksPluginSettings, MagicLinkService } from '@arkenivajs/security-magiclink';

export async function startMagicLinks(settings: MagicLinksPluginSettings) {
  const app = await createApplication({
    service: { name: 'account-confirmation', version: '1.0.0', environment: 'production' },
    plugins: [loggingPlugin(), magicLinksPlugin(settings)],
  });
  await app.start();
  return { app, magic: app.resolve<MagicLinkService>(MAGICLINK_CAPABILITY) };
}
```

## Settings and trust

Provider methods retain their captured implementation and original receiver.
Callable `bind`, `name` and `length` properties are never evaluated. Proxy providers
or callbacks, accessors and prototype traversal beyond 32 levels fail configuration
validation; later method replacement does not alter captured ports.

`stateStore` supplies all seven `SecurityTransactionalStore` methods,
`securityLevel` and a positive integer `operationTimeoutMs` up to 30000.
`hmac` supplies actual HMAC-SHA256 digest/verification through an external secret
provider; `signingKeyRef` is a secret reference. Key bytes must never enter the
application database. Verification must be constant-time and version-aware,
retain required prior keys, and return a real boolean. Startup tests both a
valid proof and an altered message. No permissive fallback exists.

The verifier domain is `arkenivajs.magiclink.verifier.v1`. The independent
`arkenivajs.magiclink.owner.v1` blind-index domain must remain stable across
verifier-key rotations while shared quota records exist. Its result is formatted
through SHA-256. Bind key references and domains to an approved provider policy.

`authority.require` independently authenticates management and resolves current
account/tenant membership on every operation. Fixed action names are
`magiclink.issue.<intent>`, `magiclink.consume.<intent>` and `magiclink.revoke`.
Caller identities, object brands and stored selectors are never proof of current
authorization. A valid bearer can enter passwordless account resolution; its
owner must still be enabled and authorized by the trusted application directory.
That resolution does not require a separate browser login. Missing, denied or
unavailable authority fails closed.

`MagicLinkAuthority` remains structurally compatible with
`TrustedSecurityAuthority`. Its context completion adds `magicLink` hints
(`issueId`, `intent`, `tenantId`) so the authority can independently resolve the
stored tenant without fabricating a `VerifiedTenantContext`. The service checks
the returned canonical issuer, subject and tenant against the requested binding.
Production and development reject explicitly test-only providers; a production
label does not replace provider review.

`trustedBaseUrl` must be an explicit HTTPS URL without credentials, query or
fragment. It is never derived from request headers or a caller redirect target.
`ttlMs` is an explicit integer from 1 to 900000 (15 minutes); select a shorter
policy where appropriate for the application purpose. `maxClaimsPerHour` is an
integer from 1 to 100000. Separate fixed-hour issuance and successful-consumption
budgets share the issuer/subject/tenant binding across participating pods.
These ceilings are implementation bounds; no implicit TTL or quota is selected.

## Operations and atomic state

| Operation                                               | Result                                                                                                                |
| ------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `issue(subject, intent, options?)`                      | Returns `issueId`, `value`, `expiresAt`, `redemptionUrl` once after quota and credential commit                       |
| `consume(token, { method: 'POST', purpose }, options?)` | Verifies proof, purpose, expiry and current authority, then atomically consumes state and returns `MagicLinkIdentity` |
| `revoke(issueId, options?)`                             | Authenticates management first, checks ownership and revokes shared state; repeated authorized revocation is harmless |

Intents are `login`, `email-verify` and `account-recover`. Tokens use
`ml1.<UUID>.<base64url-secret>`. Stored rows contain minimal owner selectors,
intent, expiry, versioned keyed verifier and state. No raw credential, URL,
arbitrary claims or HMAC key is persisted. The verifier binds every security
field and the secret. Credential transition and quota increment use one native
atomic batch. Competing consumers have exactly one winner across processes.

Public expiry uses the trusted process clock. Replay records remain for at most
one hour after credential expiry so the store can distinguish expired and reused
credentials. Backend TTL/cleanup remains the storage provider's responsibility.
Definitively rejected CAS predicates receive at most eight bounded
re-evaluations. Unacknowledged mutations never grant identity and are never
retried as assumed rollbacks.

## HTTPS confirmation and delivery

URLs place token and purpose in a fragment. Deliver them through a separately
authorized mail/application channel. Never log or trace credentials or redemption
URLs. A GET, HEAD, scanner, preview or automatic page load must not consume state.
The application reads and removes the fragment locally, presents an explicit
confirmation button and sends the credential only in the body of an HTTPS POST.
Do not put it in a query, redirect, analytics event or browser storage.

Serve `Referrer-Policy: no-referrer`, restrictive CSP and `Cache-Control: no-store`;
enforce trusted Origin and the application's CSRF policy. Return generic user
failures without exposing account existence, provider errors or internal
expiry/replay classes. The [PostgreSQL HTTPS example](../../examples/postgres/magiclinks.md)
demonstrates application-owned routes and actual network tests. Its confirmation
does not create a session or change MFA assurance. Any login, recovery or account
mutation needs a separately authorized application integration. Email possession
confers neither MFA nor phishing resistance.

## Bounds, errors and observation

Each instance admits 16 physical operations without a queue. Public cancellation
and deadlines retain capacity until actual provider work settles. Shutdown
aborts calls and invalidates handles; injected providers remain application-owned.
Caller deadlines may narrow the configured positive bound. Unknown options,
arbitrary clock overrides, malformed signals, proxies and accessors are rejected.
Interrupted writes preserve `outcome: 'unknown'`.

Errors use fixed English messages and `EK_MAGICLINK_INVALID`,
`EK_MAGICLINK_EXPIRED`, `EK_MAGICLINK_REPLAY` or the applicable core code.
Optional audit/telemetry use fixed operation, intent and outcome labels, issued,
consumed, expired and replay counters, durations and physical admission gauges.
Tokens, owner identifiers, key references, verifiers and URLs are excluded from
logs, labels and spans. Delivery observation belongs to the separate transport
integration and must also exclude credentials.

Run `pnpm --filter @arkenivajs/security-magiclink test:unit` after building.
Public-artifact, PostgreSQL 17/18, signed OIDC, independent-process, verified HTTPS
and actual SDK privacy suites provide separate functional/security evidence.
Required remote CI, comparative performance and release acceptance remain
separate gates.
