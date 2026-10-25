# @arkenivajs/security-webauthn

This private workspace contains browser ceremony types and an internal compatibility
adapter for `@simplewebauthn/server` 14.0.3. The package root exports types only.
The adapter verifies cryptographic responses; successful primitive verification
requires subsequent trusted authorization and durable state transitions before it
can establish MFA evidence. No factor service is exposed by this version.

The internal adapter pins user presence and verification, exact challenge/RP/origin
checks and the upstream EdDSA, ES256 and RS256 algorithm set. It rejects cross-origin
ceremonies without an explicit embedding policy. Browser input is bounded and
snapshotted before asynchronous verification. Errors contain no response, challenge,
credential identifier, signature or upstream diagnostic text.

Registration tests use disposable synthetic authenticators and `none` attestation.
Authentication tests sign real assertions with ephemeral P-256 keys and verify
negative origin, RP, challenge, flags, credential and signature cases. These tests
exercise the upstream primitive; durable replay protection, account-handle policy,
credential state CAS, browser integration and a complete factor service have
separate acceptance requirements.

The private service boundary validates the complete credential-store and trusted
authority interfaces, captures provider methods at construction and rejects
test-only providers in production. Production is the default; only test instances
may inject a clock. Every call has a 30-second default deadline, with explicit
timeouts limited to integer milliseconds from 1 through 120,000. Provider failures,
late results and cancellation cannot grant permission or expose provider diagnostics.

Session-bound operations require fresh runtime identity resolution and their own
authorization decision. Registration requires authentication within five minutes;
revocation also requires an independently authorized grant verified within one minute.
Attempt limits use SHA-256-scoped RP/account/tenant buckets: five attempts per minute
for each account/action, twenty per minute for each anonymous RP/action. Anonymous
passwordless resolution is opt-in and follows cryptographic credential verification;
it does not require an existing session. These boundaries are tested internally;
the package still exposes no complete factor-service factory.

The private ceremony protocol stores a SHA-256 challenge digest bound to the RP,
origin set, required verification, attestation and TTL policy. Claims also bind the
exact operation, issuer, account, tenant and primary session. A failed proof consumes
its claimed ceremony; a retry needs a fresh one. Passwordless ceremonies use a
separate anonymous namespace and cannot claim a session-bound ceremony. Changing
security configuration invalidates unfinished challenges from the previous policy.

Browser JSON snapshots are limited to 1 MiB, 4,096 values and 16 nesting levels.
They reject accessors, custom prototypes, serialization hooks, cycles and unsafe
object keys. Extracted identifiers and challenges are explicitly unverified until
the upstream signature/RP/origin/UV checks complete. Shared test-map races verify
the claim protocol; real durable-store and credential-state acceptance remain open.

Private credential helpers validate and snapshot backend metadata before use,
including a bounded copy of public-key bytes. They compare ownership and optional
assertion handles, enforce monotonic nonzero counters and keep backup eligibility
immutable. Every accepted authentication, including `0 → 0`, requires an acknowledged
version change. Revocation uses the same revision; conflicts require a fresh ceremony
and never trigger an automatic retry. Invalid receipts or uncertain persistence
return no success. These row-transition tests use an atomic simulator; production
acceptance still requires the complete service and shared-database race tests.

```sh
pnpm install --frozen-lockfile
pnpm build
pnpm --filter @arkenivajs/security-webauthn test
```

The browser package is not a runtime dependency. This module does not load USB/HID
drivers or access browser APIs. See the [upstream server documentation](https://simplewebauthn.dev/docs/packages/server)
and [third-party notices](THIRD_PARTY_NOTICES.md).
